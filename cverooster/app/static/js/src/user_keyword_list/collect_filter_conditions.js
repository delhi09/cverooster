var collect_filter_conditions = function () {
    var params = [];
    var keyword = $("input[type='text']#input_keyword").val();
    if (keyword) {
        params.push("keyword=" + keyword);
    }
    return params;
};