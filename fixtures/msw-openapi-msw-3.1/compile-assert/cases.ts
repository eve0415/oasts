import { createOpenApiHttp } from "openapi-msw";

import type { paths } from "../generated-msw/msw/paths.js";

const http = createOpenApiHttp<paths>();

const correctHandler = http.get("/pets/{petId}", ({ params, query, response }) => {
  const petId: string = params.petId;
  const include: "owner" | null = query.get("include");
  void include;
  return response("200").json({ id: Number(petId), name: "Miso" });
});

const emptyHandler = http.get("/pets/{petId}", ({ response }) => response("204").empty());

const requestBodyHandler = http.post("/pets/{petId}", async ({ request, response }) => {
  const body = await request.json();
  const name: string = body.name;
  return response("201").json({ id: 1, name });
});

http.get("/pets/{petId}", ({ response }) => {
  // @ts-expect-error status 201 is not declared for GET /pets/{petId}
  return response("201").json({ id: 1, name: "Miso" });
});

http.get("/pets/{petId}", ({ response }) => {
  // @ts-expect-error the 200 response has no text content type
  return response("200").text("Miso");
});

http.get("/pets/{petId}", ({ response }) => {
  // @ts-expect-error the JSON response body requires a numeric id
  return response("200").json({ id: "1", name: "Miso" });
});

export { correctHandler, emptyHandler, requestBodyHandler };
