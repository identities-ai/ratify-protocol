package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/identities-ai/ratify-protocol/v2/internal/statussource"
)

// googleProvider reads Google Workspace through the Admin SDK Directory API
// with a service account that has domain-wide delegation for two read-only
// scopes. Apart from the token request it sends only GET requests.
//
// A user loses authority at once when the Directory reports suspended or
// archived. A deleted user (404 notFound) or one who is not a direct or
// nested member of every configured group is absent; absence revokes once it
// has lasted the source's confirmation window, because nested membership
// changes can take minutes to appear. Any other answer, including a missing
// suspended field or a member row that cannot be evaluated, yields no
// snapshot.
type googleProvider struct {
	ClientEmail string
	Key         *rsa.PrivateKey
	Subject     string   // the admin user the service account acts as
	GroupIDs    []string // immutable group IDs, never addresses
	TokenURL    string   // https://oauth2.googleapis.com/token
	AdminURL    string   // https://admin.googleapis.com/admin/directory/v1
	Client      *http.Client
	Now         func() time.Time
}

const scopes = "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.group.member.readonly"

var (
	googleUserID = regexp.MustCompile(`^[0-9]{1,32}$`)
	groupID      = regexp.MustCompile(`^[0-9a-z]{1,64}$`)
	emailAddress = regexp.MustCompile(`^[^@\s/]+@[^@\s/]+$`)
)

// absenceConfirm is how long a deleted or removed user must stay absent
// before the absence revokes; Google documents that nested membership
// changes can take up to 10 minutes to appear.
const absenceConfirm = 10 * time.Minute

// maxMemberPages bounds one group listing (200 members per page).
const maxMemberPages = 5000

func (p *googleProvider) Name() string               { return "Google Workspace" }
func (p *googleProvider) ValidUserID(id string) bool { return googleUserID.MatchString(id) }
func (p *googleProvider) UserIDHint() string {
	return "an immutable Google Workspace user ID (numeric)"
}

func (p *googleProvider) Begin(ctx context.Context) (statussource.Read, error) {
	token, err := p.token(ctx)
	if err != nil {
		return statussource.Read{}, err
	}
	groups := make([]map[string]bool, 0, len(p.GroupIDs))
	for _, group := range p.GroupIDs {
		members, err := p.members(ctx, token, group)
		if err != nil {
			return statussource.Read{}, fmt.Errorf("group %s: %w", group, err)
		}
		groups = append(groups, members)
	}
	check := func(ctx context.Context, id string) error {
		var user struct {
			ID        string `json:"id"`
			Suspended *bool  `json:"suspended"`
			Archived  bool   `json:"archived"`
		}
		found, err := p.get(ctx, token, p.AdminURL+"/users/"+url.PathEscape(id)+"?projection=basic", &user)
		if err != nil {
			return err
		}
		if !found {
			return statussource.ErrAbsent // deleted, or not yet visible
		}
		// Only the immutable user ID is trusted: an email can be reassigned.
		if user.ID != id {
			return errors.New("the Directory returned a different user than the mapping names")
		}
		if user.Suspended == nil {
			return errors.New("the Directory did not return suspended")
		}
		if *user.Suspended || user.Archived {
			return statussource.ErrRevoked
		}
		for _, members := range groups {
			if !members[id] {
				return statussource.ErrAbsent
			}
		}
		return nil
	}
	// When the read ends, every configured group must still exist with the
	// same members, so neither a group deleted mid-read nor a member
	// restored mid-read can leave a stale decision in force.
	finish := func(ctx context.Context) error {
		for i, group := range p.GroupIDs {
			members, err := p.members(ctx, token, group)
			if err != nil {
				return fmt.Errorf("group %s: %w", group, err)
			}
			if !maps.Equal(members, groups[i]) {
				return fmt.Errorf("group %s membership changed during the read", group)
			}
		}
		return nil
	}
	return statussource.Read{Check: check, Finish: finish}, nil
}

// token exchanges a service account JWT (RS256, sub = the admin user) for
// an access token, as Google documents for domain-wide delegation.
func (p *googleProvider) token(ctx context.Context) (string, error) {
	now := p.Now().Unix()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{"iss": p.ClientEmail, "sub": p.Subject, "scope": scopes,
		"aud": p.TokenURL, "iat": now, "exp": now + 3600})
	if err != nil {
		return "", err
	}
	unsigned := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.Key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion": {unsigned + "." + base64.RawURLEncoding.EncodeToString(sig)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := p.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Google token request failed: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(data) > 1<<20 {
		return "", errors.New("Google token response could not be read")
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Google token endpoint answered HTTP %d", response.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if json.Unmarshal(data, &body) != nil || body.AccessToken == "" || !strings.EqualFold(body.TokenType, "Bearer") {
		return "", errors.New("Google token response has no bearer access token")
	}
	return body.AccessToken, nil
}

// members lists a group's direct and nested user members, following
// nextPageToken to the last page. A missing group or a row that cannot be evaluated is an
// error, never a revocation of every user.
func (p *googleProvider) members(ctx context.Context, token, group string) (map[string]bool, error) {
	members := map[string]bool{}
	seen := map[string]bool{}
	pageToken := ""
	for pages := 0; ; pages++ {
		if pages == maxMemberPages || seen[pageToken] {
			return nil, errors.New("Directory member listing did not end")
		}
		seen[pageToken] = true
		query := url.Values{"includeDerivedMembership": {"true"}, "maxResults": {"200"}}
		if pageToken != "" {
			query.Set("pageToken", pageToken)
		}
		var page struct {
			Kind    string `json:"kind"`
			Members []struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"members"`
			NextPageToken string `json:"nextPageToken"`
		}
		found, err := p.get(ctx, token, p.AdminURL+"/groups/"+url.PathEscape(group)+"/members?"+query.Encode(), &page)
		if err != nil {
			return nil, err
		}
		// An empty group omits members; the kind confirms a members listing.
		if !found || page.Kind != "admin#directory#members" {
			return nil, errors.New("Directory group is missing or its member listing is malformed")
		}
		for _, member := range page.Members {
			if member.ID == "" {
				return nil, errors.New("Directory member row has no ID")
			}
			switch member.Type {
			case "USER":
				if !googleUserID.MatchString(member.ID) {
					return nil, errors.New("Directory member row has an invalid user ID")
				}
				members[member.ID] = true
			case "GROUP", "EXTERNAL":
				// Nested groups are expanded by includeDerivedMembership;
				// external accounts are outside the domain and never mapped.
			default:
				// CUSTOMER (every user in the domain) and unknown types
				// cannot be resolved to users here.
				return nil, fmt.Errorf("Directory member type %q cannot be evaluated; list users or groups instead", member.Type)
			}
		}
		if page.NextPageToken == "" {
			return members, nil
		}
		pageToken = page.NextPageToken
	}
}

// get reads one Directory object. It reports found=false only for a 404
// whose Google error reason is notFound; every other non-200 answer,
// redirect, or malformed body is an error.
func (p *googleProvider) get(ctx context.Context, token, target string, into any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	response, err := p.Client.Do(req)
	if err != nil {
		return false, fmt.Errorf("Directory read failed: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 8<<20+1))
	if err != nil || len(data) > 8<<20 {
		return false, errors.New("Directory response could not be read")
	}
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		var e struct {
			Error struct {
				Errors []struct {
					Reason string `json:"reason"`
				} `json:"errors"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &e) != nil || len(e.Error.Errors) != 1 || e.Error.Errors[0].Reason != "notFound" {
			return false, errors.New("Directory answered 404 without its notFound error")
		}
		return false, nil
	default:
		return false, fmt.Errorf("Directory answered HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(into); err != nil {
		return false, errors.New("Directory response is not JSON")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return false, errors.New("Directory response has trailing data")
	}
	return true, nil
}

type config struct {
	statussource.Config
	AdminSubject string   `json:"admin_subject"`
	GroupIDs     []string `json:"group_ids"`
}

// serviceAccountKey is the JSON key file Google Cloud issues for a service
// account; only these fields are used.
type serviceAccountKey struct {
	Type        string `json:"type"`
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
	TokenURI    string `json:"token_uri"`
}

const googleTokenURL = "https://oauth2.googleapis.com/token"

// loadConfig reads the JSON config, the service account key file named by
// GOOGLE_SERVICE_ACCOUNT_KEY_FILE, and IAM_SOURCE_BEARER_TOKEN.
func loadConfig(path string, getenv func(string) string) (config, *statussource.Source, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return config{}, nil, err
	}
	var cfg config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return config{}, nil, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return config{}, nil, err
	}
	if !emailAddress.MatchString(cfg.AdminSubject) {
		return config{}, nil, errors.New("admin_subject must be the email of the read-only admin the service account acts as")
	}
	// A group address can later be reassigned to another group; the ID cannot.
	if len(cfg.GroupIDs) == 0 {
		return config{}, nil, errors.New("group_ids must name at least one Google group ID")
	}
	for _, group := range cfg.GroupIDs {
		if !groupID.MatchString(group) {
			return config{}, nil, fmt.Errorf("group ID %q is not an immutable Google group ID (use the id from groups.get, not the email)", group)
		}
	}
	keyFile := getenv("GOOGLE_SERVICE_ACCOUNT_KEY_FILE")
	if keyFile == "" || getenv("IAM_SOURCE_BEARER_TOKEN") == "" {
		return config{}, nil, errors.New("GOOGLE_SERVICE_ACCOUNT_KEY_FILE and IAM_SOURCE_BEARER_TOKEN are required")
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		return config{}, nil, fmt.Errorf("service account key: %w", err)
	}
	var sa serviceAccountKey
	if err := json.Unmarshal(raw, &sa); err != nil || sa.Type != "service_account" || !emailAddress.MatchString(sa.ClientEmail) {
		return config{}, nil, errors.New("GOOGLE_SERVICE_ACCOUNT_KEY_FILE must be a service account JSON key")
	}
	// The signed assertion goes only to Google's documented token endpoint.
	if sa.TokenURI != googleTokenURL {
		return config{}, nil, fmt.Errorf("service account token_uri must be %s", googleTokenURL)
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return config{}, nil, errors.New("service account private_key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, isRSA := parsed.(*rsa.PrivateKey)
	if err != nil || !isRSA {
		return config{}, nil, errors.New("service account private_key must be an RSA PKCS #8 key")
	}
	provider := &googleProvider{ClientEmail: sa.ClientEmail, Key: key, Subject: cfg.AdminSubject, GroupIDs: cfg.GroupIDs,
		TokenURL: googleTokenURL, AdminURL: "https://admin.googleapis.com/admin/directory/v1",
		Client: statussource.NoRedirectClient(&http.Client{}), Now: time.Now}
	mapping, err := statussource.ReadMapping(cfg.MappingFile, provider)
	if err != nil {
		return config{}, nil, err
	}
	return cfg, &statussource.Source{Provider: provider, RevisionPrefix: "google-", AbsenceConfirm: absenceConfirm, IssuerID: cfg.IssuerID,
		StatePath: cfg.StateFile, Mapping: mapping, MappingFile: cfg.MappingFile, Now: time.Now}, nil
}
