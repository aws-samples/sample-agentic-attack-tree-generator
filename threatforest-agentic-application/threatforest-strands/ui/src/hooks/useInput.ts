import { useEffect } from 'react';
import { useInput as inkUseInput } from 'ink';

export type KeyHandler = (key: string) => void;

export const useKeyboard = (handlers: Record<string, KeyHandler>) => {
  inkUseInput((input, key) => {
    // Handle special keys
    if (key.escape) handlers['escape']?.('escape');
    if (key.return) handlers['enter']?.('enter');
    if (key.upArrow) handlers['up']?.('up');
    if (key.downArrow) handlers['down']?.('down');
    if (key.leftArrow) handlers['left']?.('left');
    if (key.rightArrow) handlers['right']?.('right');
    
    // Handle letter keys
    const lower = input.toLowerCase();
    if (handlers[lower]) handlers[lower](lower);
    
    // Handle any key
    if (handlers['any']) handlers['any'](input);
  });
};
