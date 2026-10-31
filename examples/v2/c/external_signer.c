/*
 * Ratify Protocol v2 external signer: a signing provider holds the private
 * key; the library prepares each typed statement and verifies every
 * returned signature before using it.
 *
 * The provider here is an in-process stand-in for a remote signing service.
 * It uses OpenSSL libcrypto (3.5 or later, for ML-DSA-65) as its own
 * cryptography, so the library never sees its private keys. The interface
 * makes no claim about any particular KMS or HSM.
 *
 * Build and run: examples/v2/c/test.sh
 */
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "example_util.h"

#define START 1800000000LL
/* 32 bytes of 0x42: a fixed challenge, since nothing is verified live here. */
#define CHALLENGE_B64 "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="

/* A signing service. Its private keys never leave it. It signs in direct
 * mode: Ed25519 over the 77-byte message M and ML-DSA-65 over M with the
 * library-chosen context string. */
typedef struct {
    const char *name;
    RatifyV2PublicKey pub;
    EVP_PKEY *ed;
    EVP_PKEY *ml;
    char log[160];
} provider;

static void provider_init(provider *p, const char *name) {
    size_t len;
    p->name = name;
    p->log[0] = '\0';
    p->ed = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    p->ml = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-65");
    if (!p->ed || !p->ml) fail("provider key generation failed (OpenSSL 3.5 or later is required)");
    len = sizeof p->pub.ed25519;
    if (!EVP_PKEY_get_raw_public_key(p->ed, p->pub.ed25519, &len) || len != sizeof p->pub.ed25519)
        fail("provider Ed25519 public key");
    len = sizeof p->pub.ml_dsa_65;
    if (!EVP_PKEY_get_raw_public_key(p->ml, p->pub.ml_dsa_65, &len) || len != sizeof p->pub.ml_dsa_65)
        fail("provider ML-DSA-65 public key");
}

static int32_t provider_public_key(void *user, RatifyV2PublicKey *out) {
    *out = ((const provider *)user)->pub;
    return 0;
}

static int32_t provider_sign(void *user, const RatifyV2SignRequest *req, RatifyV2Signature *out) {
    provider *p = user;
    /* A provider refuses any request for a key it does not hold. */
    if (req->mode != RatifyV2SignerDirect || memcmp(req->public_key, &p->pub, sizeof p->pub) != 0) return 1;
    snprintf(p->log, sizeof p->log, "%s signed: mode=direct message=%zu bytes context=%.*s", p->name,
             (size_t)req->message.len, (int)req->ml_dsa_context.len, (const char *)req->ml_dsa_context.ptr);

    size_t len = sizeof out->ed25519;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    int ok = md && EVP_DigestSignInit(md, NULL, NULL, NULL, p->ed) == 1 &&
             EVP_DigestSign(md, out->ed25519, &len, req->message.ptr, req->message.len) == 1;
    EVP_MD_CTX_free(md);
    if (!ok) return 1;
    out->ed25519_len = len;

    EVP_SIGNATURE *alg = EVP_SIGNATURE_fetch(NULL, "ML-DSA-65", NULL);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, p->ml, NULL);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void *)req->ml_dsa_context.ptr,
                                          req->ml_dsa_context.len),
        OSSL_PARAM_construct_end(),
    };
    len = sizeof out->ml_dsa_65;
    ok = alg && ctx && EVP_PKEY_sign_message_init(ctx, alg, params) == 1 &&
         EVP_PKEY_sign(ctx, out->ml_dsa_65, &len, req->message.ptr, req->message.len) == 1;
    EVP_PKEY_CTX_free(ctx);
    EVP_SIGNATURE_free(alg);
    if (!ok) return 1;
    out->ml_dsa_65_len = len;
    return 0;
}

int main(void) {
    printf("Ratify Protocol v2 external signer\n");

    provider issuer, agent;
    provider_init(&issuer, "issuer provider");
    provider_init(&agent, "agent provider");
    RatifyV2ExternalSigner issuer_signer = {&issuer, RatifyV2SignerDirect, provider_public_key, provider_sign};
    RatifyV2ExternalSigner agent_signer = {&agent, RatifyV2SignerDirect, provider_public_key, provider_sign};
    RatifyV2KeyPair *verifier;
    CHECK(ratify_v2_keypair_generate(&verifier, NULL, NULL));
    char issuer_id[RATIFY_V2_KEY_ID_BUF_LEN], agent_id[RATIFY_V2_KEY_ID_BUF_LEN], verifier_id[RATIFY_V2_KEY_ID_BUF_LEN];
    CHECK(ratify_v2_public_key_id(&issuer.pub, issuer_id, sizeof issuer_id));
    CHECK(ratify_v2_public_key_id(&agent.pub, agent_id, sizeof agent_id));
    CHECK(ratify_v2_keypair_key_id(verifier, verifier_id, sizeof verifier_id));
    char *issuer_json = key_json(&issuer.pub), *agent_json = key_json(&agent.pub);

    char *cert_in = format(
        "{\"cert_id\":\"external-signer-cert-1\",\"constraints\":[],\"expires_at\":%lld,\"issued_at\":%lld,"
        "\"issuer_id\":\"%s\",\"issuer_pub_key\":%s,\"scope\":[\"files:read\"],\"subject_id\":\"%s\","
        "\"subject_pub_key\":%s,\"version\":2}",
        START + 86400, START, issuer_id, issuer_json, agent_id, agent_json);
    RatifyV2Buffer cert_buf;
    CHECK(ratify_v2_sign_delegation_certificate((const uint8_t *)cert_in, strlen(cert_in), NULL, &issuer_signer,
                                                &cert_buf));
    printf("%s\n", issuer.log);
    int cert_ok = ratify_v2_verify_object(RatifyV2KindDelegationCertificate, cert_buf.ptr, cert_buf.len, NULL, NULL) == 0;
    printf("delegation: signature verified by the SDK (%s)\n", cert_ok ? "true" : "false");
    char *cert = take_string(cert_buf);

    char *bundle_in = format(
        "{\"agent_id\":\"%s\",\"agent_pub_key\":%s,\"challenge\":\"%s\",\"challenge_at\":%lld,\"delegations\":[%s],"
        "\"session_context\":null,\"stream_id\":null,\"stream_seq\":null,\"verifier_id\":\"%s\",\"version\":2}",
        agent_id, agent_json, CHALLENGE_B64, START, cert, verifier_id);
    RatifyV2Buffer bundle;
    CHECK(ratify_v2_sign_proof_bundle((const uint8_t *)bundle_in, strlen(bundle_in), NULL, &agent_signer, &bundle));
    printf("%s\n", agent.log);
    int bundle_ok = ratify_v2_proof_bundle_verify_signatures(bundle.ptr, bundle.len, NULL, 0, NULL) == 0;
    printf("proof bundle: signatures verified by the SDK (%s)\n", bundle_ok ? "true" : "false");

    /* A faulty provider returns an ML-DSA-65 signature from a different key.
     * The library verifies before use, so nothing is signed. */
    EVP_PKEY *wrong = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-65");
    if (!wrong) fail("key generation failed");
    EVP_PKEY *right = agent.ml;
    agent.ml = wrong;
    RatifyV2Buffer refused_buf = {0};
    int32_t refused = ratify_v2_sign_proof_bundle((const uint8_t *)bundle_in, strlen(bundle_in), NULL, &agent_signer,
                                                  &refused_buf);
    printf("faulty provider: refused (%s)\n", ratify_v2_error_class_str(refused));

    ratify_v2_buffer_free(refused_buf);
    EVP_PKEY_free(wrong);
    EVP_PKEY_free(right);
    EVP_PKEY_free(agent.ed);
    EVP_PKEY_free(issuer.ed);
    EVP_PKEY_free(issuer.ml);
    ratify_v2_buffer_free(bundle);
    free(bundle_in);
    free(cert);
    free(cert_in);
    free(issuer_json);
    free(agent_json);
    ratify_v2_keypair_free(verifier);
    return 0;
}
