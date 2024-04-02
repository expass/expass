
import {
    ExPassInterface,
    interfaces,
    ExPassModuleFactoryParams,
    ExPassModuleFactory,
    DefaultConfig,
} from '@expass/core';
import { NodeExPass as NodeExPassInterface } from '../domain/nodeexpass';
import { NodeCrypto } from './crypto';
import { NodeScryptEncoder } from './encoder';


type ExPassConfigFlag = interfaces.ConfigFlag;
type ExPassConfig = interfaces.ExPassConfig;
type ExPassConfigParams = interfaces.ExPassConfigParams;

const getExPassService = (() => {
    let exPassService: ExPassInterface | null = null;

    return (): ExPassInterface => {
        if (!exPassService) {
            exPassService = ExPassModuleFactory({
                Crypto: NodeCrypto,
                Encoder: NodeScryptEncoder,
            });
        }
        return exPassService;
    };
})();

export interface Options extends ExPassConfigParams {};

type PartialExPassConfig = Partial<ExPassConfig>;

export class NodeExPass implements NodeExPassInterface {
    readonly #secret: Buffer;
    #exPass: ExPassInterface;
    #config: {
        config: PartialExPassConfig,
        params: ExPassConfigParams,
    };

    constructor(secret: string | Buffer, options: Options = {}) {
        if (Buffer.isBuffer(secret)) {
            this.#secret = secret;
        } else {
            this.#secret = Buffer.from(secret, 'utf8');
        }

        this.#config = {
            config: Object.keys(options)
                .filter((k) => k in DefaultConfig)
                .reduce<PartialExPassConfig>((acc, _k) => {
                    const k = _k as ExPassConfigFlag;
                    return {
                        ...acc,
                        [k]: options[k] as any,
                    };
                }, {}),
            params: options,
        };

        this.#exPass = getExPassService();
    }

    get #exPassConfig(): PartialExPassConfig {
        return {...this.#config.config};
    }

    get #exPassConfigParams(): ExPassConfigParams {
        return {
            ...this.#exPassConfig,
            ...this.#config.params
        };
    }

    async encode(password: string): Promise<string> {
        return this.#exPass.encode(
            password,
            this.#secret,
            this.#config.config,
        );
    }

    async verify(password: string, hash: string): Promise<boolean> {
        return this.#exPass.compare(
            password,
            hash,
            this.#secret,
            this.#config.params,
        )
            .catch((err) => {
                if (err.code === 'ERR_OSSL_BAD_DECRYPT') {
                    return false;
                }

                throw err;
            });
    }
}
