# Credential Gate Server Example

The example directory contains a simple example of how to use the credential gate server.
It has a simple web server that exposes a few endpoints:
- `/` - a simple hello world endpoint
- `/config` - view configuration for the gate server 
- `/gate` - the gate itself, accepts a presentation submission and returns a gate response
- `/sample` - produces a sample response to be used with the gate. accepts a query parameter for whether to return a 
valid or invalid response (e.g. `?valid=true`)
- `/responses` - view all responses that have been sent to the gate server

# Running the example

From the root directory of the project, run...
```bash
go run ./example
```

##  Verify the server is running

Make sure the server is running:

```bash
curl localhost:8080
```

You should see a response like:

```json
{
  "message": "Hello, world!"
}
```

### Get the Config

```bash
curl localhost:8080/config
```

You should see a response like:

```json
{
  "adminDid": "did:key:z6MkuFxTcaRYiGGe4FUhWhioeMD2MArhR1Jx1gC9gGLB5cfn",
  "presentationDefinition": {
    "id": "5dcfa118-f7ce-4979-9b24-bb94b135d063",
    "name": "Example Credential Gate Presentation Definition",
    "purpose": "Provide a credential showing your name",
    "format": {
      "jwt_vp": {
        "alg": [
          "EdDSA",
          "ES256K",
          "ES256",
          "ES384",
          "PS256"
        ]
      }
    },
    "input_descriptors": [
      {
        "id": "ef415c20-fd11-4b87-b6c9-1226c199adfa",
        "name": "Example Credential Gate Input Descriptor",
        "purpose": "Provide a credential showing your name",
        "format": {
          "jwt_vc": {
            "alg": [
              "EdDSA",
              "ES256K",
              "ES256",
              "ES384",
              "PS256"
            ]
          }
        },
        "constraints": {
          "fields": [
            {
              "path": [
                "$.sub"
              ],
              "filter": {
                "type": "string",
                "pattern": "did:key:*"
              }
            },
            {
              "path": [
                "$.iss"
              ],
              "filter": {
                "type": "string",
                "pattern": "did:key:*"
              }
            },
            {
              "path": [
                "$.exp"
              ]
            },
            {
              "path": [
                "$.vc.credentialSubject.name"
              ],
              "filter": {
                "type": "string",
                "minLength": 2
              }
            }
          ]
        }
      }
    ]
  }
}
```

## Submit a sample submission to the gate

### Get a valid sample submission

```bash
curl localhost:8080/sample
```

You should see a response like:

```json
{
  "submissionJwt": "<long submission JWT here>"
}
```

### Send a valid sample submission to the gate

```bash
curl -X POST -d "<long submission JWT here>" localhost:8080/gate
```

```json
{ 
  "accessGranted": true,
  "message":"access granted"
}
```

### Get an invalid sample submission

```bash
curl localhost:8080/sample?valid=false
```

You should see a response like:

```json
{
  "submissionJwt": "<long submission JWT here>"
}
```

### Send an invalid sample submission to the gate

```bash
curl -X POST -d "<long submission JWT here>" localhost:8080/gate
```

```json
{
  "accessGranted": false,
  "message": "error validating presentation submission: verifying presentation submission: input descriptor\u003cef415c20-fd11-4b87-b6c9-1226c199adfa\u003e not fulfilled for non-optional field: : matching path for claim could not be found"
}
```
