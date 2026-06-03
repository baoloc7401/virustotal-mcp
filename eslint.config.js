// @ts-check
import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/**", "node_modules/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      globals: {
        process: "readonly",
        console: "readonly",
        fetch: "readonly",
        FormData: "readonly",
        Blob: "readonly",
        Buffer: "readonly",
        setTimeout: "readonly",
      },
    },
    rules: {
      // VirusTotal v3 responses are large, loosely-typed JSON we deliberately
      // navigate with `any` in vtClient/format rather than modeling every field.
      "@typescript-eslint/no-explicit-any": "off",
    },
  },
);
