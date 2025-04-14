import { AwaitHandler } from './awaitHandler';

/**
 * A helper function to delay the execution of a promise.
 *
 * @param ms - The number of milliseconds to delay.
 * @param type - The type of the promise.
 *
 * @returns The promise.
 */
const delay = async (ms: number, type: 'success' | 'error' = 'success') =>
  new Promise((resolve, reject) =>
    setTimeout(() => {
      if (type === 'error') {
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
  });
});
