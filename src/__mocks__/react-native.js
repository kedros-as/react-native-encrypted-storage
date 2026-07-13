const RNEncryptedStorage = {
  setItem: jest.fn(() => Promise.resolve()),
  getItem: jest.fn(() => Promise.resolve('{ "foo": 1 }')),
  removeItem: jest.fn(() => Promise.resolve()),
  clear: jest.fn(() => Promise.resolve()),
};

module.exports = {
  TurboModuleRegistry: {
    getEnforcing: jest.fn((name) => {
      if (name === 'RNEncryptedStorage') {
        return RNEncryptedStorage;
      }

      throw new Error(`No mock registered for TurboModule "${name}"`);
    }),
  },
};
