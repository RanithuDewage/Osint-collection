
from modules.core.registry import ModuleRegistry


class ModuleRunner:
    def __init__(self, registry=None):
        self.registry = registry or ModuleRegistry()
        self._custom_modules = {}

    def register(self, name, module):
        self._custom_modules[name] = module

    def run(self, name, target):
        if name in self._custom_modules:
            module = self._custom_modules[name]
        else:
            module = self.registry.get(name)

        return module(target)

    def list_modules(self):
        if self._custom_modules:
            return list(self._custom_modules.keys())

        return self.registry.list_modules()


