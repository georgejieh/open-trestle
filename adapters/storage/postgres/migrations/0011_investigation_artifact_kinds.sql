ALTER TABLE open_trestle_artifacts
    DROP CONSTRAINT open_trestle_artifacts_kind_check,
    ADD CONSTRAINT open_trestle_artifacts_kind_check CHECK (kind IN (
        'source_snapshot', 'change_model', 'deterministic_evidence',
        'retrieval_result', 'context_packet', 'candidate_batch',
        'verification_batch', 'verified_finding_set', 'publication_plan',
        'run_export', 'task_input', 'webhook_delivery', 'source_file',
        'publication_receipt', 'investigation_turn', 'investigation_tool_result'
    ));
