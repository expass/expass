
import { ExPassConfig, ExPassPackage } from './interfaces';

export interface Packager {
    pack: (salt: Buffer, body: Buffer, config: ExPassConfig) => string;
    unpack: (data: string) => ExPassPackage;
}
