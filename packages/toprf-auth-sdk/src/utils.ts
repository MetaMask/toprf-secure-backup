import { NODE_URLS } from './constants';

/**
 * Randomly selects a node URL from the available nodes
 *
 * @returns An object containing:
 * - url: The URL of the randomly selected node
 * - index: The 1-based index of the selected node
 */
export const getRandomNode = (): { url: string; index: string } => {
  const randomIndex = Math.floor(Math.random() * NODE_URLS.length);
  return {
    url: NODE_URLS[randomIndex],
    index: String(randomIndex + 1),
  };
};
