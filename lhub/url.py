from .common.helpers import format_version


class URLs:
    __version = None

    def __init__(self, server_name, init_version=None):
        self.server_name = server_name.lower().strip()
        if init_version:
            self._current_version = init_version

    @property
    def _current_version(self):
        if self.__version:
            return int(float(self.__version))
        return self.__version

    @_current_version.setter
    def _current_version(self, val):
        self.__version = format_version(val)

    @property
    def base(self):
        return f"https://{self.server_name}"

    @property
    def alert_fetch(self):
        return f"{self.base}/api/alert/alert-{{}}"

    @property
    def alerts_search_advanced(self):
        return f"{self.base}/api/alert/search/advanced"

    @property
    def alerts_search_basic(self):
        return f"{self.base}/api/alert/search/basic"

    @property
    def alerts_search_validate(self):
        return f"{self.base}/api/alert/search/validate"

    @property
    def baselines(self):
        return f"{self.base}/api/content-management/content/baseline"

    @property
    def batch_reprocess(self):
        return f"{self.base}/api/demo/batch-{{}}"

    @property
    def batch_results_by_id(self):
        return f"{self.base}/api/demo/batch-{{}}/correlations"

    @property
    def case(self):
        return f"{self.base}/api/case/{{case_id}}"

    # ToDo Is this still relevant??
    @property
    def case_get_basic_details(self):
        return f"{self.case}/basicDetails"

    # ToDo Is this still relevant??
    @property
    def case_get_custom_fields(self):
        return f"{self.case}/fields"

    @property
    def case_update_linked_alerts(self):
        return self.case

    @property
    def case_status_list_workflows(self):
        return f"{self.base}/api/cases/status-workflow"

    @property
    def case_status_workflow_by_id(self):
        return f"{self.base}/api/cases/status-workflow/statusworkflow-{{}}"

    @property
    def cases_get_prefix(self):
        return f"{self.base}/api/cases/prefix"

    @property
    def cases_search_advanced(self):
        return f"{self.base}/api/cases/v2/search/advanced"

    @property
    def cases_search_validate(self):
        return f"{self.base}/api/cases/search/validate"

    @property
    def case_types(self):
        return f"{self.base}/api/case-types"

    @property
    def command(self):
        return f"{self.base}/commands/{{}}"

    @property
    def command_execute(self):
        return f"{self.base}/api/commands/execute"

    @property
    def commands(self):
        return f"{self.base}/api/content-management/content/command"

    @property
    def connection_status(self):
        return f"{self.base}/api/connection/status"

    @property
    def connections(self):
        return f"{self.base}/api/content-management/content/connection"

    @property
    def custom_list_data(self):
        return f"{self.base}/api/lists/{{}}/data"

    @property
    def custom_list_data_with_filtering(self):
        return f"{self.base}/api/lists/{{}}/search"

    @property
    def custom_lists(self):
        return f"{self.base}/api/content-management/content/customList"

    # ToDo Token auth not supported as of 2022-03-09 (m92)
    @property
    def dashboard(self):
        """Get the config for a single dashboard"""
        return f"{self.base}/api/dashboards/v2/{{}}"

    # ToDo Token auth not supported as of 2022-03-09 (m92)
    @property
    def dashboard_data(self):
        """Get widget data from a single dashboard's current state"""
        return f"{self.base}/api/dashboards/v2/{{}}/data"

    # ToDo Token auth not supported as of 2022-03-09 (m92)
    @property
    def dashboards(self):
        """List all dashboards"""
        return f"{self.base}/api/dashboards/v2"

    @property
    def dashboards_and_widgets(self):
        """
        List all dashboards via Content Exchange, including widget definitions. Includes dashboards not yet imported from Content Exchange.
        IDs are not correct if being used to fetch dashboard data: shows ID with spaces like the name, but real IDs have underscores.
        :return:
        """
        return f"{self.base}/api/content-exchange/browse/Dashboard"

    @property
    def entities_search(self):
        return f"{self.base}/api/search/entities/{{}}"

    @property
    def event_types(self):
        # Not sure when the old one changed, but it doesn't work in 70
        if self._current_version < 70:
            return f"{self.base}/api/eventtype-flowrefs"
        return f"{self.base}/api/content-management/content/eventType"

    @property
    def fields(self):
        return f"{self.base}/api/fields"

    @property
    def fields_get_computed(self):
        # Fetch the config of computed fields, i.e. lh_url, lh_filehash, and lh_ipaddress (example: regex exclusions)
        return f"{self.base}/api/fields/computed"

    @property
    def flow_export(self):
        return f"{self.base}/api/flow/flow-{{}}/export"

    @property
    def integrations(self):
        return f"{self.base}/api/content-exchange/browse/Integration"

    @property
    def login(self):
        return f"{self.base}/api/login"

    @property
    def logout(self):
        return f"{self.base}/api/logout"

    @property
    def me(self):
        return f"{self.base}/api/user-management/me"

    @property
    def modules(self):
        return f"{self.base}/api/content-exchange/browse/Module"

    @property
    def ml_models(self):
        return f"{self.base}/api/listMLModels"

    @property
    def notebooks_attach(self):
        return f"{self.base}/api/notebook/attachNotebooksToEntity"

    @property
    def notebooks_attached(self):
        return f"{self.base}/api/notebook/attachedNotebooks"

    @property
    def notebooks_list(self):
        return f"{self.base}/api/content-management/content/notebook"

    @property
    def playbooks_list(self):
        return f"{self.base}/api/content-management/content/playbook"

    @property
    def playbook_versions(self):
        return f"{self.base}/api/flow/flow-{{}}/versions"

    @property
    def rule_set(self):
        return f"{self.base}/api/demo/ruleSet-{{}}"

    @property
    def rule_sets(self):
        return f"{self.base}/api/demo/hub/ruleSets"

    @property
    def saml_configs(self):
        return f"{self.base}/api/saml"

    @property
    def stream_batches(self):
        return f"{self.base}/api/stream/stream-{{}}/batches/filter"

    @property
    def stream_by_id(self):
        return f"{self.base}/api/stream/stream-{{}}"

    @property
    def stream_states(self):
        return f"{self.base}/api/stream/states"

    @property
    def stream_pause(self):
        return f"{self.base}/api/stream/pause"

    @property
    def stream_resume(self):
        return f"{self.base}/api/stream/resume"

    @property
    def streams(self):
        return f"{self.base}/api/content-management/content/stream"

    @property
    def user_groups(self):
        return f"{self.user_group_create}/search"

    @property
    def user_group(self):
        return f"{self.user_group_create}/{{}}"

    @property
    def user_group_create(self):
        return f"{self.base}/api/user-management/user-group"

    @property
    def user_group_delete(self):
        return f"{self.user_group_create}/delete"

    @property
    def users(self):
        return f"{self.base}/api/user-management/user/search"

    @property
    def user(self):
        # For updating user preferences & settings, not for fetching them. To fetch them, use the "me" call (/api/user-management/me)
        return f"{self.base}/api/user-management/user/{{}}"

    @property
    def user_create(self):
        return f"{self.base}/api/user-management/user"

    @property
    def user_delete(self):
        return f"{self.base}/api/user-management/user/delete"

    @property
    def user_legacy(self):
        # For looking up user by ID, or for password resets
        return f"{self.base}/api/demo/user-{{}}"

    @property
    def version(self):
        return f"{self.base}/api/version"

    # ToDo confirm Token auth
    @property
    def widget_data(self):
        """Get widget data from a single dashboard's current state"""
        return f"{self.base}/api/dashboards/v2/{{dashboard_id}}/widget/{{widget_id}}/data"

    @property
    def get_password_settings(self):
        return f"{self.base}/api/config/getPasswordSettings"

    @property
    def update_password_settings(self):
        return f"{self.base}/api/config/setPasswordSettings"
