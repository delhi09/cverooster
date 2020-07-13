var collect_filter_conditions = function () {
    var severity = $("select#select_severity").val() != ALL ? $("select#select_severity").val() : null;
    var year = $("select#select_year").val() != ALL ? $("select#select_year").val() : null;
    var labels = [];
    if (!$("input[type='checkbox']#label_all").prop("checked")) {
        $("input[type='checkbox'].check_label").each(function () {
            if ($(this).prop('checked')) {
                labels.push($(this).val());
            }
        });
    }
    var enable_user_keyword = 0;
    $("input[type='radio'].check_enable_user_keyword").each(function () {
        if ($(this).prop('checked')) {
            enable_user_keyword = $(this).val();
        }
        return false;
    });
    var keyword = $("input[type='text']#input_keyword").val();
    var params = [];
    if (severity) {
        params.push("severity=" + severity);
    }
    if (year) {
        params.push("year=" + year);
    }
    if (labels) {
        for (var i in labels) {
            params.push("label=" + labels[i]);
        }
    }
    if (enable_user_keyword != null) {
        params.push("enable_user_keyword=" + enable_user_keyword);
    }
    if (keyword) {
        params.push("keyword=" + keyword);
    }
    return params;
};