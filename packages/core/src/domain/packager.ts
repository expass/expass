
import { VersionedExPassConfig, ExPassPackage } from './interfaces';

export interface Packager {
    pack: (salt: Buffer, body: Buffer, config: VersionedExPassConfig) => string;
    unpack: (data: string) => ExPassPackage;
}
