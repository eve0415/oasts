import { searchMessagesHandler } from "../generated-msw/msw/handlers/searchmessages.js";

searchMessagesHandler(({ query, respond }) => {
  const sort: "relevance" | "timestamp" | undefined = query.sort_by;
  const authors: readonly ("user" | "bot" | "webhook")[] | undefined = query.author_type;
  const filters: readonly ("link" | "embed" | "file")[] | undefined = query.has;
  const limit: 10 | 25 | undefined = query.limit;
  const state: "active" | null | undefined = query.state;
  const ratio: 0.5 | 1 | undefined = query.ratio;
  const enabled: true | undefined = query.enabled;
  const empty: null | undefined = query.empty;
  void sort;
  void authors;
  void filters;
  void limit;
  void state;
  void ratio;
  void enabled;
  void empty;
  return respond({ match: 204, status: 204 });
});
