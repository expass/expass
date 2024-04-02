
import 'reflect-metadata';
import QS from 'querystring';
import { singleton } from 'tsyringe';
import { 
    ExPassPackage,
    ExPassConfig,
    VersionedExPassConfig,
    ConfigFlag,
    ConfigFlagRef,
    ConfigFlagTypeRef,
    ResumedExPassConfig,
    ResumedExPassConfigFlag,
    ResumedExPassConfigFlagRef,
} from '../domain/interfaces';
import { ExPassInvalidHashError } from './errors';
import { Packager as PackagerInterface } from '../domain/packager';
import { DefaultConfig } from './defaultconfig';

type MapResumeFlag = keyof Omit<ResumedExPassConfig, 'v'>;

export const configMap: Record<ConfigFlag, MapResumeFlag> = {
    preHashAlgorithm: 'pra',
    postHashAlgorithm: 'poa',
    hmacAlgorithm: 'h',
    saltLength: 'sl',
    power: 'p',
    encodeHashLenght: 'el',
    keyDerivationPower: 'kp',
    cipherAlgorithm: 'ca',
}

type ExtratedConfig = Partial<ExPassConfig>;

/**
 * Pack/Unpack password hashes
 */
@singleton()
export class Packager implements PackagerInterface {

    protected _cleanBase64(str: string): string {
        return str
            .replace(/\+/g, '.')
            .replace(/\//g, '_')
            .replace(/=+$/g, '');
    }

    protected _fixBase64(str: string): string {
        return str
            .replace(/\./g, '+')
            .replace(/_/g, '/')
            .replace(/=+$/g, '');
    }

    pack(salt: Buffer, body: Buffer, versionedConfig: VersionedExPassConfig): string {
        const saltStr = this._cleanBase64(salt.toString('base64'));
        const bodyStr = this._cleanBase64(body.toString('base64'));

        const {
            version,
            ...config
        } = versionedConfig;

        const ops: ResumedExPassConfig = Object.keys(configMap)
            .filter((key) => config[key as ConfigFlag] !== DefaultConfig[key as ConfigFlag])
            .reduce<ResumedExPassConfig>((acc, _key) => {
                const key = _key as ConfigFlag;
                const skey = configMap[key] as ResumedExPassConfigFlag;
                return {
                    ...acc,
                    [skey]: config[key] as any,
                };
            }, { v: '1'})
        ;

        const opsStr = QS.stringify(ops as any);

        return `$expass$${opsStr}$${saltStr}$${bodyStr}`;
    }

    unpack(data: string): ExPassPackage {
        const parts = data.split('$');

        if (
            !parts.length ||
            parts.length !== 5 ||
            parts[1] !== 'expass'
        ) {
            throw new ExPassInvalidHashError();
        }

        const [
            opsStr,
            saltStr,
            bodyStr,
        ] = parts.slice(2);

        const readOps = QS.parse(opsStr);

        if (!('v' in readOps)) {
            throw new ExPassInvalidHashError();
        }

        const ops: ResumedExPassConfig = readOps as unknown as ResumedExPassConfig;
        const version = ops.v;

        const config: ExPassConfig = Object.keys(configMap)
            .reduce<ExPassConfig>((acc, _key) => {
                const key : ConfigFlag = _key as ConfigFlag;
                const skey : keyof Omit<ResumedExPassConfig, 'v'> = configMap[key];
                if (skey in ops && typeof ops[skey] !== 'undefined') {
                    const k: ConfigFlagRef<typeof key> = key;
                    let value : ConfigFlagTypeRef<typeof key> = ops[skey]!;
                    if (
                        k === 'saltLength' ||
                        k === 'power' ||
                        k === 'keyDerivationPower' ||
                        k === 'encodeHashLenght'
                    ) {
                        value = parseInt(value as any, 10);
                    }
                    return {
                        ...acc,
                        [k]: value,
                    };
                }
                return acc;
            }, {...DefaultConfig} as ExPassConfig);

        const salt = Buffer.from(this._fixBase64(saltStr), 'base64');
        const body = Buffer.from(this._fixBase64(bodyStr), 'base64');

        if (!salt.length || !body.length) {
            throw new ExPassInvalidHashError(); 
        }

        return { version, salt, body, config };
    }

}
