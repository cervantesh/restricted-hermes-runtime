# ADR 0002: Mattermost for the restricted conversational edge

Mattermost is selected over Rocket.Chat and Matrix for this bounded internal
slice because the required deployment is centralized and self-hosted, and the
needed surface is limited to authenticated WebSocket events plus a stable REST
API. Matrix federation and its homeserver trust model add boundaries this slice
does not need. Rocket.Chat would require a second independently audited client
contract without reducing the authorization work.

The decision does not make Mattermost a security authority. A standalone edge
revalidates every channel and root against an offline-signed policy, then calls
only the existing restricted `conversation.sock` API. It never imports normal
Hermes, provider code, tools, plugins, memory, or attachment processing.
