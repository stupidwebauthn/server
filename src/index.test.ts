import app from ".";
import { testClient } from "hono/testing";
import { expect, test } from "bun:test";

const client = testClient(app);

test("should be able to return root page", async () => {
  const res = await client.index.$get();
  expect(res.status).toEqual(200);
  expect(await res.text()).toEqual("Hello World!");
});
