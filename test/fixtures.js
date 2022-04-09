import { createEdIssuer, createRSAIssuer } from "./util.js"

/** did:key:z6Mkk89bC3JrVqKie71YEcc5M1SMVxuCgNx6zLZ8SYJsxALi */
export const alice = createEdIssuer(
  "U+bzp2GaFQHso587iSFWPSeCzbSfn/CbNHEz7ilKRZ1UQMmMS7qq4UhTzKn3X9Nj/4xgrwa+UqhMOeo4Ki8JUw=="
)

/** did:key:z6MkffDZCkCTWreg8868fG1FGFogcJj5X6PY93pPcWDn9bob */
export const bob = createEdIssuer(
  "G4+QCX1b3a45IzQsQd4gFMMe0UB1UOx9bCsh8uOiKLER69eAvVXvc8P2yc4Iig42Bv7JD2zJxhyFALyTKBHipg=="
)

/** did:key:z6MktafZTREjJkvV5mfJxcLpNBoVPwDLhTuMg9ng7dY4zMAL */
export const mallory = createEdIssuer(
  "LR9AL2MYkMARuvmV3MJV8sKvbSOdBtpggFCW8K62oZDR6UViSXdSV/dDcD8S9xVjS61vh62JITx7qmLgfQUSZQ=="
)

export const service = createRSAIssuer()

/**
 * @param {string} did
 */
export function didToName(did) {
  if (did === alice.did()) return "alice"
  if (did === bob.did()) return "bob"
  if (did === mallory.did()) return "mallory"
  return did
}
