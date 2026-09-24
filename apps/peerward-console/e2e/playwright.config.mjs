export default {
  testDir: ".",
  testMatch: "*.spec.mjs",
  timeout: 60_000,
  // A cold debug WASM build can take more than five seconds to hydrate in CI.
  expect: { timeout: 15_000 },
  workers: 1,
  use: {
    headless: true,
    locale: "en-US",
    timezoneId: "UTC",
    colorScheme: "light",
    reducedMotion: "reduce",
  },
};
