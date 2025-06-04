# `@metamask/toprf-secure-backup`

## Installation

`yarn add @metamask/toprf-secure-backup`

or

`npm install @metamask/toprf-secure-backup`

## Contributing

This package is part of a monorepo. Instructions for contributing can be found in the [monorepo README](https://github.com/MetaMask/toprf-secure-backup#readme).

## Security Considerations

This SDK handles sensitive cryptographic material including passwords, seeds, authentication tokens, and private keys.

### JavaScript Memory Limitations

**Important**: JavaScript's garbage collector provides no guarantees about when sensitive data is removed from memory. While the SDK performs best-effort cleanup internally, complete memory clearing cannot be guaranteed.

### Best Practices

1. **Minimize sensitive data lifetime** - Use keys immediately, don't store in variables
2. **Avoid framework state** - Don't store keys in React state, Redux, or similar
3. **Clear references** - Set variables to `null` and call `array.fill(0)` when done

```javascript
// ✅ Good: Use immediately and clear
async function decrypt(data) {
  const { encKey } = await toprfBackup.recoverEncKey(params);
  try {
    return await processData(data, encKey);
  } finally {
    encKey.fill(0);
  }
}

// ❌ Bad: Long-lived storage
this.encKey = result.encKey; // Persists in memory
```

### Potential Risks

- XSS attacks accessing memory
- Malicious browser extensions
- Memory inspection via developer tools
- System-level memory dumps

The SDK internally clears sensitive Uint8Array data (session keys, password bytes, seeds) where possible, but JavaScript strings and BigInts cannot be reliably cleared from memory.
