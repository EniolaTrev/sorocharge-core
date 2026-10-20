import js from "@eslint/js";

export default [
  {
    ignores: ["fixtures/**", "node_modules/**"],
  },
  {
    files: ["generate.mjs"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        Buffer: "readonly",
        console: "readonly",
      },
    },
    rules: js.configs.recommended.rules,
  },
];
