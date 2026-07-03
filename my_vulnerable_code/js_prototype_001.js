function merge(obj, source) {
    for (let key in source) {
        obj[key] = source[key];
    }
    return obj;
}
