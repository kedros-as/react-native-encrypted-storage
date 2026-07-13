import { TurboModuleRegistry, type TurboModule } from 'react-native';

export interface Spec extends TurboModule {
  setItem(key: string, value: string): Promise<void>;
  getItem(key: string): Promise<string | null>;
  removeItem(key: string): Promise<void>;
  clear(): Promise<void>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('RNEncryptedStorage');
