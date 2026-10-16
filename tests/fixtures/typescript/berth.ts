// Berth allocation types
import type { Boat } from './boat';
import { z } from 'zod';

export interface Berth {
  id: number;
  boat?: Boat;
}

export type Size = 'small' | 'large';

export enum Status { Free, Taken }

export class Allocator {
  allocate(size: Size): Berth { return { id: 1 }; }
}

export const isFree = (b: Berth): boolean => b.boat === undefined;

export function schema() { return z.object({ id: z.number() }); }
