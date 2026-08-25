/**
 * Copying can be refused — an insecure context, a denied permission, a browser that never grants
 * it without a gesture. Every call site needs the same answer: never let the rejection escape,
 * and never leave the button looking like it worked.
 */
export const copyText = async (text: string): Promise<boolean> => {
	try {
		await navigator.clipboard.writeText(text);
		return true;
	} catch {
		return false;
	}
};
