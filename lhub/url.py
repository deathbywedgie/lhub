class URLs:
    _version = 0

    def __init__(self, server_name):
        self.server_name = str(server_name).lower().strip()

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
    def _case_base_url(self):
        return f"{self.base}/api/case/{{case_id}}"

    @property
    def case_get_basic_details(self):
        return f"{self._case_base_url}/basicDetails"

    @property
    def case_get_custom_fields(self):
        return f"{self._case_base_url}/fields"

    @property
    def case_update_linked_alerts(self):
        return self._case_base_url

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
    def dashboard_config(self):
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
    def event_types(self):
        # Not sure when the old one changed, but it doesn't work in 70
        if self._version < 70:
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
    def rule_set(self):
        return f"{self.base}/api/demo/ruleSet-{{}}"

    @property
    def rule_sets(self):
        return f"{self.base}/api/demo/hub/ruleSets"

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
        return f"{self.base}/api/user-management/user-group/search"

    @property
    def users(self):
        return f"{self.base}/api/user-management/user/search"

    @property
    def version(self):
        return f"{self.base}/api/version"
