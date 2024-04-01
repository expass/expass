
import QS from 'querystring';
import { 
    ExPassPackage,
    ExPassConfig,
    ConfigFlag,
    ConfigFlagRef,
    ConfigFlagTypeRef,
    ResumedExPassConfig,
    ResumedExPassConfigFlag,
    ResumedExPassConfigFlagRef,
} from '../domain/interfaces';
import { Packager as PackagerInterface } from '../domain/packager';
import { DefaultConfig } from './defaultconfig';

export const configMap: Record<ConfigFlag, ResumedExPassConfigFlag> = {
    preHashAlgorithm: 'pra',
    postHashAlgorithm: 'poa',
    saltLength: 'sl',
    power: 'p',
    keyDerivationAlgorithm: 'kda',
    keyDerivationIterations: 'kdi',
    cipherAlgorithm: 'ca',
}

type ExtratedConfig = Partial<ExPassConfig>;

/**
 * Pack/Unpack password hashes
 */
export class Packager implements PackagerInterface {

    protected _cleanBase64(str: string): string {
        return str
            .replace(/\+/, '.')
            .replace(/\//, '_')
            .replace(/=+$/, '');
    }

    protected _fixBase64(str: string): string {
        return str
            .replace(/\./, '+')
            .replace(/_/, '/')
            .replace(/=+$/, '');
    }

    pack(salt: Buffer, body: Buffer, config: ExPassConfig): string {
        const saltStr = this._cleanBase64(salt.toString('base64'));
        const bodyStr = this._cleanBase64(body.toString('base64'));

        const ops: ResumedExPassConfig = Object.keys(configMap)
            .filter((key) => config[key as ConfigFlag] !== DefaultConfig[key as ConfigFlag])
            .reduce<ResumedExPassConfig>((acc, _key) => {
                const key = _key as ConfigFlag;
                const skey = configMap[key] as ResumedExPassConfigFlag;
                if (key in config) {
                    acc[skey] = config[key] as any;
                }
                return acc;
            }, {})
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
            throw new Error('Invalid hash format');
        }

        const [
            opsStr,
            saltStr,
            bodyStr,
        ] = parts.slice(2);

        const ops = QS.parse(opsStr) as ResumedExPassConfig;

        const config: ExPassConfig = Object.keys(configMap)
            .reduce<ExPassConfig>((acc, _key) => {
                const key : ConfigFlag = _key as ConfigFlag;
                const skey : ResumedExPassConfigFlag = configMap[key];
                if (skey in ops && typeof ops[skey] !== 'undefined') {
                    const k: ConfigFlagRef<typeof key> = key;
                    let value : ConfigFlagTypeRef<typeof key> = ops[skey]!;
                    if (
                        k === 'saltLength' ||
                        k === 'power' ||
                        k === 'keyDerivationIterations'
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
            throw new Error('Invalid hash format');
        }

        return { salt, body, config };
    }

}
