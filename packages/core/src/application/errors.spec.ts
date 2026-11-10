
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

describe('ExPassForbiddenParamValueError', () => {
    
    it('Should be a default message', () => {
        const error = new errors.ExPassForbiddenParamValueError();
        expect(error.message).toBe('Forbidden parameter value');
    });

});
