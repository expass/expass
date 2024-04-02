
import * as errors from './errors';

describe('ExPassInvalidHashError', () => {

    it('Should be a default message', () => {
        const error = new errors.ExPassInvalidHashError();
        expect(error.message).toBe('Invalid hash format');
    });

});

describe('ExPassVersionMismatchError', () => {

    it('Should be a default message', () => {
        const error = new errors.ExPassVersionMismatchError();
        expect(error.message).toBe('Version mismatch');
    });

});

describe('ExPassForbidenParamValueError', () => {
    
    it('Should be a default message', () => {
        const error = new errors.ExPassForbidenParamValueError();
        expect(error.message).toBe('Forbiden parameter value');
    });

});
