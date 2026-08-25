/**
 * What the playground opens with. It compiles clean — the first thing a visitor sees should be
 * working output, not a configuration error.
 */

export const DEFAULT_DOCUMENT = `openapi: 3.1.0
info:
  title: Pets
  version: 1.0.0
servers:
  - url: https://api.example.test
paths:
  /pets/{petId}:
    get:
      operationId: getPet
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: A pet.
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Pet"
components:
  schemas:
    Pet:
      type: object
      required: [id, name]
      properties:
        id:
          type: string
        name:
          type: string
        tag:
          type: string
        birthday:
          type: string
          format: date
`;

export const DEFAULT_CONFIG = `schemaVersion: 1
input:
  path: ./openapi.yaml
output: ./generated
artifacts:
  types: true
  client: true
  zod: true
validation:
  engine: zod
  response: true
`;
