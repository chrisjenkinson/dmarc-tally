use tally_aws::dynamodb::DynamoReportRepository;
use tally_core::ports::ReportRepository;

#[test]
fn dynamodb_adapter_satisfies_portable_repository_contract() {
    fn require_report_repository<T: ReportRepository>() {}
    require_report_repository::<DynamoReportRepository>();
}
