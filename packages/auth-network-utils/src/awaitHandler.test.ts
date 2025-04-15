import { AwaitHandler } from './awaitHandler';

/**
 * A helper function to delay the execution of a promise.
 *
 * @param ms - The number of milliseconds to delay.
 * @param type - The type of the promise.
 *
 * @returns The promise.
 */
const delay = async (ms: number, type: 'success' | 'failure' = 'success') =>
  new Promise((resolve, reject) =>
    setTimeout(() => {
      if (type === 'failure') {
        reject(new Error('error'));
      }
      resolve(ms);
    }, ms),
  );

describe('await handler', function () {
  it('test await handler', async () => {
    const awaitHandler = new AwaitHandler<string>([
      delay(1000).then(() => '1'),
      delay(2000).then(() => '2'),
      delay(3000).then(() => '3'),
      delay(1000).then(() => '4'),
      delay(3000).then(() => '5'),
    ]);

    await awaitHandler.waitForResults(2);
    expect(
      awaitHandler.getResults().filter((result) => result !== null),
    ).toHaveLength(2);
    await awaitHandler.waitForResults(3);
    expect(
      awaitHandler.getResults().filter((result) => result !== null),
    ).toHaveLength(3);

    await delay(1000);
    expect(
      awaitHandler.getResults().filter((result) => result !== null),
    ).toHaveLength(5);

    awaitHandler.reset();
    expect(awaitHandler.getResults()).toStrictEqual([]);
    expect(awaitHandler.getErrors()).toStrictEqual([]);
  });

  it('test await handler with error', async () => {
    const awaitHandler = new AwaitHandler<string>([
      delay(1000, 'failure').then(() => '1'),
      delay(2000, 'failure').then(() => '2'),
      delay(3000).then(() => '3'),
      delay(1000, 'failure').then(() => '4'),
      delay(3000).then(() => '5'),
    ]);

    await expect(awaitHandler.waitForResults(3)).rejects.toThrow(
      'Number of promises that failed is greater than wait threshold',
    );
  });

  it('test await handler with error less that threshold', async () => {
    const awaitHandler = new AwaitHandler<string>([
      delay(1000, 'failure').then(() => '1'),
      delay(2000, 'failure').then(() => '2'),
      delay(3000).then(() => '3'),
      delay(1000, 'failure').then(() => '4'),
      delay(3000).then(() => '5'),
    ]);

    const results = await awaitHandler.waitForResults(2);
    expect(results.filter((result) => result !== null)).toHaveLength(2);

    expect(
      awaitHandler.getErrors().filter((error) => error !== null),
    ).toHaveLength(3);
  });
});
