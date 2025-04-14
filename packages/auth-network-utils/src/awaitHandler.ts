/**
 * A class that handles the awaiting of number of promises.
 *
 * @example
 * ```ts
 * const awaitHandler = new AwaitHandler<string>([
 *   delay(1000).then(() => '1'),
 *   delay(2000).then(() => '2'),
 * ]);
 * await awaitHandler.waitForResults(2);
 * console.log(awaitHandler.getResults());
 * ```
 */
export class AwaitHandler<T> {
  appendedPromises: Promise<T>[];

  results: T[];

  errors: Error[];

  /**
   * @param listofPromises - The list of promises to be awaited.
   */
  constructor(listofPromises: Promise<T>[]) {
    this.results = Array(listofPromises.length).fill(null);
    this.errors = Array(listofPromises.length).fill(null);
    this.appendedPromises = listofPromises.map(async (task) => {
      const index = listofPromises.indexOf(task);
      try {
        const promise = await task;
        this.results[index] = promise;
        return promise;
      } catch (error) {
        this.errors[index] = error as Error;
        throw error;
      }
    });
  }

  /**
   * Wait for the results to be resolved.
   *
   * @param waitFor - The number of results to wait for.
   *
   * @returns The results.
   */
  async waitForResults(waitFor: number): Promise<T[]> {
    let success = 0;
    let failure = 0;
    const promisesLength = this.appendedPromises.length;
    return new Promise((resolve, reject) => {
      const allPromises = this.appendedPromises.map(async (task) => {
        try {
          const result = await task;
          success += 1;
          if (success >= waitFor) {
            resolve(this.results);
          }
          return result;
        } catch {
          failure += 1;
          if (failure >= promisesLength - waitFor) {
            reject(
              new Error(
                `Number of promises that failed is greater than ${promisesLength - waitFor}`,
              ),
            );
          }
          return null;
        }
      });

      Promise.allSettled(allPromises)
        .then((tasks) => {
          if (this.results.length >= waitFor) {
            resolve(this.results);
          } else {
            reject(
              new Error(
                `waitFor is greater than the number of promises: ${waitFor} > ${this.results.length}`,
              ),
            );
          }
          return tasks;
        })
        .catch((e) => {
          reject(e as Error);
          return e;
        });
    });
  }

  /**
   * Get the results.
   *
   * @returns The results.
   */
  getResults(): T[] {
    return this.results;
  }

  /**
   * Get the errors.
   *
   * @returns The errors.
   */
  getErrors(): Error[] {
    return this.errors;
  }

  /**
   * Reset the results and errors.
   */
  reset(): void {
    this.results = [];
    this.errors = [];
    this.appendedPromises = [];
  }
}
