export type DeepPartial<T> = {
    [K in keyof T]?:
        | (T[K] extends Record<string, any> ? DeepPartial<T[K]> : T[K])
        | undefined;
};

export function deepMerge<T extends Record<string, any>>(
    target: T,
    ...sources: DeepPartial<T>[]
): T {
    if (typeof target !== 'object' || target === null) {
        throw new Error('Target must be a non-null object');
    }

    for (const source of sources) {
        if (source && typeof source === 'object') {
            for (const key in source) {
                if (source.hasOwnProperty(key)) {
                    const sourceValue = source[key];
                    const targetValue = target[key];

                    if (
                        typeof sourceValue === 'object' &&
                        sourceValue !== null
                    ) {
                        // Recursively merge if both are objects
                        const merged = deepMerge(
                            (targetValue !== undefined
                                ? targetValue
                                : {}) as T[keyof T],
                            sourceValue as Partial<T[keyof T]>
                        ) as T[keyof T];

                        Object.assign(target, { [key]: merged });
                    } else if (
                        sourceValue !== undefined ||
                        targetValue === undefined
                    ) {
                        // Replace undefined target keys or take defined source value

                        Object.assign(target, { [key]: sourceValue });
                    }
                }
            }
        }
    }

    return target;
}
export function catchErrors<T, E extends new (message?: string) => Error>(
    promise: Promise<T>,
    errorsToCatch?: E[]
): Promise<[undefined, T] | [InstanceType<E>]> {
    return promise
        .then((result) => {
            return [undefined, result] as [undefined, T];
        })
        .catch((error) => {
            if (typeof errorsToCatch == 'undefined') return [error];

            if (errorsToCatch.some((e) => e instanceof error)) return [error];

            throw error;
        });
}
