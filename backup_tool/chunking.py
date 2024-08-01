class RabinKarp:
    def __init__(self, window_size, prime=31, mod=2**13):
        self.window_size = window_size
        self.prime = prime
        self.mod = mod
        self.prime_power = pow(prime, window_size - 1, mod)

    def chunk_boundaries(self, data):
        hash_val = 0
        boundaries = []
        for i in range(len(data)):
            if i < self.window_size:
                hash_val = (hash_val * self.prime + ord(data[i])) % self.mod
            else:
                hash_val = (hash_val * self.prime + ord(data[i]) - self.prime_power * ord(data[i - self.window_size])) % self.mod

            if hash_val == 0:
                boundaries.append(i + 1)

        if boundaries[-1] != len(data):
            boundaries.append(len(data))

        return boundaries
