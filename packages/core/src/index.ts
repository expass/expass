
import 'reflect-metadata';
import { container as tsyringeContainer } from 'tsyringe';

import { ExPass as ExPassInterface } from './domain/expass';
import { Cipher as CipherInterface } from './domain/cipher';
import { Crypto as CryptoInterface } from './domain/crypto';
import { Encoder as EncoderInterface } from './domain/encoder';
import { Hasher as HasherInterface } from './domain/hasher';
import { Packager as PackagerInterface } from './domain/packager';

import { ExPass } from './application/expass';
import { Packager } from './application/packager';
export { DefaultConfig } from './application/defaultconfig';

export * as interfaces from './domain/interfaces';

export {
    ExPassInterface,
    CipherInterface,
    CryptoInterface,
    EncoderInterface,
    HasherInterface,
    PackagerInterface,
    ExPass,
    Packager,
};

export interface ExPassModuleFactoryParams {
    Crypto: new () => CryptoInterface;
    Encoder: new () => EncoderInterface;
    Packager?: new () => PackagerInterface;
}

export function ExPassModuleFactory (dependecies: ExPassModuleFactoryParams) : ExPassInterface {
    const container = tsyringeContainer.createChildContainer();

    container.register<CryptoInterface>('Crypto', { useClass: dependecies.Crypto });
    container.register<EncoderInterface>('Encoder', { useClass: dependecies.Encoder });
    if (dependecies.Packager) {
        container.register<PackagerInterface>('Packager', { useClass: dependecies.Packager });
    } else {
        container.register<PackagerInterface>('Packager', { useClass: Packager });
    }

    return container.resolve<ExPassInterface>(ExPass);
}
