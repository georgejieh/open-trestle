ALTER TABLE open_trestle_artifacts
    DROP CONSTRAINT open_trestle_artifacts_kind_check,
    ADD CONSTRAINT open_trestle_artifacts_kind_check CHECK (kind IN (
        'source_snapshot', 'change_model', 'deterministic_evidence',
        'retrieval_result', 'context_packet', 'candidate_batch',
        'verification_batch', 'verified_finding_set', 'publication_plan',
        'run_export', 'task_input', 'webhook_delivery', 'source_file',
        'publication_receipt'
    )),
    DROP CONSTRAINT open_trestle_artifacts_origin_check,
    ADD CONSTRAINT open_trestle_artifacts_origin_check CHECK (origin IN (
        'host', 'repository', 'deterministic_tool', 'model',
        'independent_verifier', 'policy', 'memory'
    ));
