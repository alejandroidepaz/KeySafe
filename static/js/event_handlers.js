function validate_password(value){
    var result;
    var strongRegex = new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{10,})");
    if (strongRegex.test(value)){
        result = true;
    } else{
        result = false;
    }
    return result;
}

$(document).ready(function(){

    $('#generate_password_checkbox').change(function() {
        if(this.checked) {
            document.querySelector("#password").readOnly = true;
        } else{
            document.querySelector("#password").readOnly = false;
        }  
    });

    $(function() {
        $('#add_password_btn').click(function() {

            var form_data = new FormData();
            var label = $("#label").val();
            form_data.append("label", label );
            if ($("#generate_password_checkbox").is(":checked")){
                form_data.append("generate_password", "True");
            } else{
                if (validate_password($("#password").val())){
                    form_data.append("generate_password", "False");
                    form_data.append("password", $("#password").val());
                } else{
                    alert("Password must contain a minimum of 10 characters, including at least: one uppercase letter, one lowercase letter, one number, and one special character.")
                    $("#password").val('');
                    $("#label").val('');
                    return null;
                }
            }

            var csrftoken = $('meta[name=csrf-token]').attr('content')

            $.ajaxSetup({
                beforeSend: function(xhr, settings) {
                    if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
                        xhr.setRequestHeader("X-CSRFToken", csrftoken)
                    }
                }
            })

            $.ajax({
            
                type: 'POST',
                url: '/add_password',
                data: form_data,
                contentType: false,
                cache: false,
                processData: false,
                success: function(data) {
                    $(".modal-header button").click();

                    var new_row = document.createElement("tr");
                    new_row.id = label;
                    var labels_length = document.getElementById("labels_table").rows.length;
                    var length_node = document.createElement("td");
                    length_node.id = labels_length;
                    length_node.innerHTML = labels_length.toString();
                    new_row.appendChild(length_node)

                    let label_node = document.createElement("td");
                    label_node.innerHTML = label;
                    new_row.appendChild(label_node);

                    let pass_node = document.createElement("td");
                    let pass_btn_node = document.createElement("button");
                    pass_btn_node.innerHTML = "VIEW PASSWORD";
                    pass_btn_node.className = "view_password_btn";
                    pass_btn_node.type = "button";
                    pass_btn_node.name = label;
                    pass_node.appendChild(pass_btn_node);

                    let del_btn_node = document.createElement("button");
                    del_btn_node.innerHTML = "DELETE";
                    del_btn_node.className = "del_password_btn";
                    del_btn_node.type = "button";
                    del_btn_node.name = label;
                    pass_node.appendChild(del_btn_node);

                    new_row.appendChild(pass_node);

                    $("#labels_list").append(new_row);

                    $("#password").val('');
                    $("#label").val('');
                    $("#generate_password_checkbox").checked = false;

                    alert("We've updated your profile with the secured data!")
                },
            });
        });
    });

    $(function() {

        $('#labels_list').on("click", ".view_password_btn", function() {

            let label = this.name;
            var form_data = new FormData();
            form_data.append("label", label);
            console.log(label);

            var csrftoken = $('meta[name=csrf-token]').attr('content')

            $.ajaxSetup({
                beforeSend: function(xhr, settings) {
                    if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
                        xhr.setRequestHeader("X-CSRFToken", csrftoken)
                    }
                }
            })

            $.ajax({
                type: 'POST',
                url: '/view_password',
                data: form_data,
                contentType: false,
                cache: false,
                processData: false,
                success: function(data) {
                    alert("Your Password is: " + data.decrypted.toString())
                },
            });
        });
    });

    $(function() {

        $('#labels_list').on("click", ".del_password_btn", function() {

            let label = this.name;
            var form_data = new FormData();
            form_data.append("label", label);
            console.log(label);

            var csrftoken = $('meta[name=csrf-token]').attr('content')

            $.ajaxSetup({
                beforeSend: function(xhr, settings) {
                    if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
                        xhr.setRequestHeader("X-CSRFToken", csrftoken)
                    }
                }
            })

            $.ajax({
                type: 'POST',
                url: '/delete_password',
                data: form_data,
                contentType: false,
                cache: false,
                processData: false,
                success: function(data) {
                    if (data.status == "success"){
                        alert("Password Successfully Deleted");
                        $( "#" + data.label ).remove();
                    }else{
                        alert("Password Was Not Successfully Deleted -- Please Try Again");
                    }
                },
            });
        });
    });

});