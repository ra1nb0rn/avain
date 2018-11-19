from core.module_manager import ModuleManager

class ModuleUpdater(ModuleManager):

    def run(self):
        self._run_modules()

    def _assign_init_values(self):
        modules = ModuleManager.find_all_prefixed_modules("modules", "module_updater")
        return (modules, "results.json", "module update", "update_module", "modules.",
                "Starting module updates", False)

    def _set_extra_module_parameters(self, module):
        pass
