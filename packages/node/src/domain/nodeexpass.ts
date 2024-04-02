
import { interfaces } from '@expass/core';

type ExPassConfigParams = interfaces.ExPassConfigParams;

export interface NodeExPass {
    encode(password: string): Promise<string>;
    verify(password: string, hash: string): Promise<boolean>;
}
