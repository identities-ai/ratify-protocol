package main

import (
	"bytes"
	"context"
	"encoding/json"
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

// entraProvider reads Microsoft Entra ID through Microsoft Graph v1.0 with
// an app registration's client credentials. It is read-only: apart from
// the token request it sends only GET requests.
//
// A user loses authority at once when Graph reports accountEnabled false.
// A deleted user (404 Request_ResourceNotFound) or one who is not a
// transitive member of every configured group is absent; absence revokes
// once it has lasted the source's confirmation window, because Graph
// replication can briefly hide a user or a membership. Any other answer,
// including a missing accountEnabled or a malformed member row, yields no
// snapshot.
type entraProvider struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	GroupIDs     []string
	LoginURL     string // https://login.microsoftonline.com
	GraphURL     string // https://graph.microsoft.com/v1.0
	Client       *http.Client
}

// graphMemberTypes are the directory object types a group can hold. Any
// other type could be a user the source cannot recognize, so it fails closed.
var graphMemberTypes = map[string]bool{"#microsoft.graph.user": true, "#microsoft.graph.group": true,
	"#microsoft.graph.device": true, "#microsoft.graph.orgContact": true, "#microsoft.graph.servicePrincipal": true}

var objectID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// absenceConfirm is how long a deleted or removed user must stay absent
// before the absence revokes, covering Graph replication delay.
const absenceConfirm = 10 * time.Minute

// maxMemberPages bounds one group listing (Graph pages hold at most 999
// objects), so a looping or endless listing fails instead of hanging.
const maxMemberPages = 2000

func (p *entraProvider) Name() string               { return "Entra ID" }
func (p *entraProvider) ValidUserID(id string) bool { return objectID.MatchString(id) }
func (p *entraProvider) UserIDHint() string {
	return "an immutable Entra user object ID (lowercase GUID)"
}

func (p *entraProvider) Begin(ctx context.Context) (statussource.Read, error) {
	token, err := p.token(ctx)
	if err != nil {
		return statussource.Read{}, err
	}
	// Each group's transitive user members, read in full for this snapshot.
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
			ID             string `json:"id"`
			AccountEnabled *bool  `json:"accountEnabled"`
		}
		found, err := p.get(ctx, token, p.GraphURL+"/users/"+url.PathEscape(id)+"?$select=id,accountEnabled", &user)
		if err != nil {
			return err
		}
		if !found {
			return statussource.ErrAbsent // deleted, or not yet replicated
		}
		// Only the immutable object ID is trusted: a UPN can be reassigned.
		if user.ID != id {
			return errors.New("Graph returned a different user than the mapping names")
		}
		if user.AccountEnabled == nil {
			return errors.New("Graph did not return accountEnabled; grant User.Read.All")
		}
		if !*user.AccountEnabled {
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

// token gets an app-only Graph token with the client credentials grant.
func (p *entraProvider) token(ctx context.Context) (string, error) {
	form := url.Values{"client_id": {p.ClientID}, "client_secret": {p.ClientSecret},
		"scope": {"https://graph.microsoft.com/.default"}, "grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.LoginURL+"/"+url.PathEscape(p.TenantID)+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := p.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Entra token request failed: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(data) > 1<<20 {
		return "", errors.New("Entra token response could not be read")
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Entra token endpoint answered HTTP %d", response.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if json.Unmarshal(data, &body) != nil || body.AccessToken == "" || !strings.EqualFold(body.TokenType, "Bearer") {
		return "", errors.New("Entra token response has no bearer access token")
	}
	return body.AccessToken, nil
}

// members lists a group's transitive user members, following
// @odata.nextLink to the last page. A missing group or malformed row is an error, never a
// revocation of every user.
func (p *entraProvider) members(ctx context.Context, token, group string) (map[string]bool, error) {
	base, err := url.Parse(p.GraphURL)
	if err != nil {
		return nil, err
	}
	collection := base.Path + "/groups/" + group + "/transitiveMembers"
	members := map[string]bool{}
	next := p.GraphURL + "/groups/" + url.PathEscape(group) + "/transitiveMembers"
	seen := map[string]bool{}
	for pages := 0; next != ""; pages++ {
		if pages == maxMemberPages || seen[next] {
			return nil, errors.New("Graph member listing did not end")
		}
		seen[next] = true
		var page struct {
			Value []struct {
				Type string `json:"@odata.type"`
				ID   string `json:"id"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		found, err := p.get(ctx, token, next, &page)
		if err != nil {
			return nil, err
		}
		if !found || page.Value == nil {
			return nil, errors.New("Graph group is missing or its member listing is malformed")
		}
		for _, member := range page.Value {
			// A row that cannot be classified could hide a member.
			if member.Type == "" || member.ID == "" {
				return nil, errors.New("Graph member row has no type or ID")
			}
			if !graphMemberTypes[member.Type] {
				return nil, fmt.Errorf("Graph member type %q is not recognized", member.Type)
			}
			if member.Type == "#microsoft.graph.user" {
				if !objectID.MatchString(member.ID) {
					return nil, errors.New("Graph member row has an invalid user ID")
				}
				members[member.ID] = true
			}
		}
		// The token is sent to every next page, so it must stay on Graph and
		// on this group's collection.
		if page.NextLink != "" {
			link, err := url.Parse(page.NextLink)
			if err != nil || link.Scheme != base.Scheme || link.Host != base.Host || link.User != nil ||
				link.Fragment != "" || link.Path != collection {
				return nil, errors.New("Graph nextLink leaves this group's member listing")
			}
		}
		next = page.NextLink
	}
	return members, nil
}

// get reads one Graph object. It reports found=false only for a 404 with
// Graph's Request_ResourceNotFound code; every other non-200 answer,
// redirect, or malformed body is an error.
func (p *entraProvider) get(ctx context.Context, token, target string, into any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	response, err := p.Client.Do(req)
	if err != nil {
		return false, fmt.Errorf("Graph read failed: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 8<<20+1))
	if err != nil || len(data) > 8<<20 {
		return false, errors.New("Graph response could not be read")
	}
	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		var e struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &e) != nil || e.Error.Code != "Request_ResourceNotFound" {
			return false, errors.New("Graph answered 404 without its not-found error")
		}
		return false, nil
	default:
		return false, fmt.Errorf("Graph answered HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(into); err != nil {
		return false, errors.New("Graph response is not JSON")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return false, errors.New("Graph response has trailing data")
	}
	return true, nil
}

type config struct {
	statussource.Config
	TenantID string   `json:"tenant_id"`
	ClientID string   `json:"client_id"`
	GroupIDs []string `json:"group_ids"`
}

// loadConfig reads the JSON config and the two secrets from the
// environment: ENTRA_CLIENT_SECRET and IAM_SOURCE_BEARER_TOKEN.
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
	if !objectID.MatchString(cfg.TenantID) || !objectID.MatchString(cfg.ClientID) {
		return config{}, nil, errors.New("tenant_id and client_id must be the lowercase GUIDs from the app registration overview")
	}
	if len(cfg.GroupIDs) == 0 {
		return config{}, nil, errors.New("group_ids must name at least one Entra group object ID")
	}
	for _, group := range cfg.GroupIDs {
		if !objectID.MatchString(group) {
			return config{}, nil, fmt.Errorf("group ID %q is not a lowercase Entra group object ID", group)
		}
	}
	secret := getenv("ENTRA_CLIENT_SECRET")
	if secret == "" || getenv("IAM_SOURCE_BEARER_TOKEN") == "" {
		return config{}, nil, errors.New("ENTRA_CLIENT_SECRET and IAM_SOURCE_BEARER_TOKEN are required")
	}
	provider := &entraProvider{TenantID: cfg.TenantID, ClientID: cfg.ClientID, ClientSecret: secret,
		GroupIDs: cfg.GroupIDs, LoginURL: "https://login.microsoftonline.com", GraphURL: "https://graph.microsoft.com/v1.0",
		Client: statussource.NoRedirectClient(&http.Client{})}
	mapping, err := statussource.ReadMapping(cfg.MappingFile, provider)
	if err != nil {
		return config{}, nil, err
	}
	return cfg, &statussource.Source{Provider: provider, RevisionPrefix: "entra-", AbsenceConfirm: absenceConfirm, IssuerID: cfg.IssuerID,
		StatePath: cfg.StateFile, Mapping: mapping, MappingFile: cfg.MappingFile, Now: time.Now}, nil
}
