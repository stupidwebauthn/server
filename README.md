# Stupid Webauthn Server

## Docker

```
docker pull lil5/stupidwebauthn-server:latest
```

## Manual Installation

To install dependencies:

```sh
bun install
```

Copy email template & environment file and configure:

```sh
cp email-example.html data/email.html
cp env-example .env
vim .env
```

To run:

```sh
bun run dev
```

open http://localhost:5178/

## Links

```
https://webauthn.passwordless.id/
https://hono.dev/docs/helpers/jwt
https://hono.dev/docs/helpers/cookie
https://bun.sh/docs/api/sqlite
```

## Flows

### Register

```mermaid
sequenceDiagram
    participant Email
    participant Client
    participant Server
    participant DB

    Note over Client, DB: Step 1 Authorize Email
    Client->>Server: Request email challenge
    Server-->>Email: Link containing challenge
    Server-->>Client: encrypted challenge cookie
    Email->>Client: Clicks on the link
    Client->>Server: Check if the challenge is valid
    Server-->>DB: Save user with Email

    Server-->>Client: Return Email Authorized JWT cookie & delete challenge cookie
    Note over Client, DB: Step 2 Authorize Passkey
    Client->>Server: Request challenge
    Server-->>Client: Get challenge in encrypted cookie and response
    Note over Client: Trigger the registration in browser
    Client->>Server: Verifying the registration on the server<br/>With challenge and encrypted cookie
    Server-->>Client: Return Authorized JWT cookie & delete challenge cookie
    Server-->>DB: Store passkey credentials with uuid
    Note over Client, DB: Client now has auth JWT
```

### Login

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant DB

    Note over Client, DB: Login
    Client->>Server: Request challenge & allowed credentials for that email
    break
        Server-->>Client: no credentials are available redirect to email registration flow
    end
    DB-->>Client: List of allowed credential IDs
    Server-->>Client: Get challenge in encrypted cookie and response
    Note over Client: Trigger authentication in browser
    Client->>Server: Verifying the authentication on the server<br/>With encrypted challenge cookie
    DB-->>Server: Match chosen credential by id and public key
    Server-->>Client: Return Authorized JWT cookie & delete challenge cookie
    Note over Client, DB: Client now has auth JWT
```

### Application middleware

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant Application
    Client->>Server: Login
    Server-->>Client: Is now authenticated with jwt cookie (with version)
    Client->>Application: Request auth route with jwt cookie
    Note over Application: Jwt is validated against secret
    Note over Application: At this point it is unknown if the server has<br/>changed the user's jwt version
    Application->>Server: Request user details from jwt cookie
    Note over Server: Jwt is validated against secret and version
    Server-->>Application: User email
    Application-->>Client: Authenticated response with user details
```
