from core.module_manager import ModuleManager

UPDATER_JOIN_TIMEOUT = 0.38

class ModuleUpdater(ModuleManager):
    def run(self):
        self._run_modules()

    @staticmethod
    def _assign_init_values():
        modules = ModuleManager.find_all_prefixed_modules("modules", "module_updater")

        return (modules, "results.json", "module update", "update_module", "modules.",
                UPDATER_JOIN_TIMEOUT, "Starting module updates", False)


    def _set_extra_module_parameters(self, module):
        pass

    def _assign_result_filename(self):
        pass

    def _add_to_results(self, module_id, module_result):
        pass
