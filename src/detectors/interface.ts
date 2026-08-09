import { InternalMatch, LeakGuardConfig } from '../types.js';

export interface Detector {
  id: string;
  name: string;
  type: string;
  description: string;
  detect(content: string, config: LeakGuardConfig): InternalMatch[];
}
