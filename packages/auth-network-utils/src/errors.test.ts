import { SomeError } from './errors';

describe('SomeError', () => {
  it('should correctly initialize properties and format message', () => {
    const mockErrors = [new Error('Error 1'), undefined, new Error('Error 3')];
    const mockResponses = [{ id: 1 }, { id: 2 }];
    const mockPredicate = new Error('Predicate failed');

    const someError = new SomeError({
      errors: mockErrors,
      responses: mockResponses,
      predicate: mockPredicate,
    });

    expect(someError.errors).toStrictEqual(mockErrors);
    expect(someError.responses).toStrictEqual(mockResponses);
    expect(someError.predicate).toStrictEqual(mockPredicate);
    expect(someError).toBeInstanceOf(Error);

    expect(someError.message).toContain('Unable to resolve enough promises.');
    expect(someError.message).toContain('errors: Error 1, , Error 3');
    expect(someError.message).toContain('predicate error: Predicate failed');
    expect(someError.message).toContain('2 responses');
    expect(someError.message).toContain('responses: [{"id":1},{"id":2}]');

    expect(someError.toString()).toStrictEqual(someError.message);
  });

  it('should handle undefined predicate and errors', () => {
    const mockErrors = [undefined, undefined];
    const mockResponses: string[] = ['responseA'];

    const someError = new SomeError<string>({
      errors: mockErrors,
      responses: mockResponses,
      predicate: undefined,
    });

    expect(someError.errors).toStrictEqual(mockErrors);
    expect(someError.responses).toStrictEqual(mockResponses);
    expect(someError.predicate).toBeUndefined();

    expect(someError.message).toContain('Unable to resolve enough promises.');
    expect(someError.message).toContain('errors: , ,');
    expect(someError.message).toContain('predicate error: unknown error');
    expect(someError.message).toContain('1 responses');
    expect(someError.message).toContain('responses: ["responseA"]');
    expect(someError.toString()).toStrictEqual(someError.message);
  });

  it('should handle empty errors and responses arrays', () => {
    const mockErrors: (Error | undefined)[] = [];
    const mockResponses: number[] = [];
    const mockPredicate = new Error('Predicate Error');

    const someError = new SomeError<number>({
      errors: mockErrors,
      responses: mockResponses,
      predicate: mockPredicate,
    });

    expect(someError.errors).toStrictEqual([]);
    expect(someError.responses).toStrictEqual([]);
    expect(someError.predicate).toStrictEqual(mockPredicate);

    expect(someError.message).toContain('Unable to resolve enough promises.');
    expect(someError.message).toContain('errors: ,');
    expect(someError.message).toContain('predicate error: Predicate Error');
    expect(someError.message).toContain('0 responses');
    expect(someError.message).toContain('responses: []');
    expect(someError.toString()).toStrictEqual(someError.message);
  });
});
