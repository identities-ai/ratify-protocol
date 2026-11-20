import Foundation
import XCTest
@testable import RatifyProtocol

/// Intent tests of the Verify MCP signer (Preview) beyond the shared vectors.
final class MCPTests: XCTestCase {
    func fixture() throws -> (MCP.ClientConfig, MCP.Challenge, SoftwarePrivateKey, [String: Any]) {
        let f = MCPRunner.load("tool-call.json")
        let config = try MCP.parseClientConfig(f.s("client_config_json"))
        let c = f.arr("cases")[0]
        let ch = try config.checkChallenge(tool: c.s("tool"), response: MCPRunner.utf8(c.s("challenge_response")),
                                           now: Int64(c.int("now")))
        return (config, ch, try MCPRunner.agentKey(f.obj("agent_key")), c)
    }

    /// A challenge is issued for one tool's scope and request hash. Letting
    /// it sign a call to another tool would hand the server a proof whose
    /// binding the signer never checked against the challenge it accepted.
    func testChallengeSignsOnlyTheToolItWasCheckedFor() throws {
        let (config, ch, key, c) = try fixture()
        let other = try MCP.newToolCall(tool: "list_agents", arguments: "{}")
        XCTAssertNotEqual(other.tool, c.s("tool"))
        XCTAssertTrue(MCPRunner.refused(.challengeRefused) {
            try MCP.signToolCall(config: config, agentKey: key, call: other, challenge: ch)
        }, "a challenge checked for one tool signed a call to another")
        // The same challenge still signs the call it was checked for.
        let same = try MCP.newToolCall(tool: c.s("tool"), arguments: c.s("arguments_json"))
        XCTAssertNoThrow(try MCP.signToolCall(config: config, agentKey: key, call: same, challenge: ch))
    }

    /// The public API cannot build a ToolCall whose digest disagrees with its
    /// arguments, but the signer re-derives the digest anyway: a proof must
    /// never bind one argument set while another is sent.
    func testToolCallWithInconsistentFieldsIsRefused() throws {
        let (config, ch, key, c) = try fixture()
        let call = try MCP.newToolCall(tool: c.s("tool"), arguments: #"{"limit":1}"#)
        let other = try MCP.newToolCall(tool: c.s("tool"), arguments: #"{"limit":2}"#)
        let swapped = MCP.ToolCall(tool: call.tool, canonicalArguments: call.canonicalArguments,
                                   payloadDigest: other.payloadDigest)
        XCTAssertTrue(MCPRunner.refused(.invalidArguments) { try config.challengeRequest(swapped) })
        XCTAssertTrue(MCPRunner.refused(.invalidArguments) {
            try MCP.signToolCall(config: config, agentKey: key, call: swapped, challenge: ch)
        }, "signed an inconsistent call")
        let spaced = MCP.ToolCall(tool: other.tool, canonicalArguments: Data(#"{ "limit":2}"#.utf8),
                                  payloadDigest: other.payloadDigest)
        XCTAssertTrue(MCPRunner.refused(.invalidArguments) {
            try MCP.signToolCall(config: config, agentKey: key, call: spaced, challenge: ch)
        }, "signed non-canonical arguments")
        let empty = MCP.ToolCall(tool: call.tool, canonicalArguments: Data(), payloadDigest: MCP.payloadDigest(Data()))
        XCTAssertTrue(MCPRunner.refused(.invalidArguments) { try config.challengeRequest(empty) })
    }

    /// The signer never signs a tool the hosted table does not name: the
    /// scope it would bind is unknown, so the server could not recompute the hash.
    func testUnknownToolIsRefusedBeforeAnyRequest() {
        XCTAssertTrue(MCPRunner.refused(.invalidArguments) { try MCP.newToolCall(tool: "delete_everything", arguments: "{}") })
    }

    /// A configuration or challenge response that is not valid UTF-8 is
    /// refused, even when the bad byte sits in a field that would be ignored.
    func testInvalidUTF8IsRefused() throws {
        /// `json` (an object) with an unknown member whose string holds a 0xFF byte.
        func withBadByte(_ json: String) -> Data {
            var bytes = Array(json.utf8)
            XCTAssertEqual(bytes.last, UInt8(ascii: "}"))
            bytes.removeLast()
            return Data(bytes + Array(#","x":"a"#.utf8) + [0xFF] + Array(#""}"#.utf8))
        }
        let (config, _, _, c) = try fixture()
        let f = MCPRunner.load("tool-call.json")
        XCTAssertNoThrow(try MCP.parseClientConfig(Data(f.s("client_config_json").utf8)))
        XCTAssertTrue(MCPRunner.refused(.invalidConfig) { try MCP.parseClientConfig(withBadByte(f.s("client_config_json"))) })
        XCTAssertTrue(MCPRunner.refused(.challengeRefused) {
            try config.checkChallenge(tool: c.s("tool"), response: withBadByte(c.s("challenge_response")), now: Int64(c.int("now")))
        })
    }
}
