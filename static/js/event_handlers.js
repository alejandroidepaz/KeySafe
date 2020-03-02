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
                console.log("password needs to be generated");
            } else{
                form_data.append("generate_password", "False");
                form_data.append("password", $("#password").val());
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

                    let new_row = document.createElement("tr");

                    var labels_length = document.getElementById("labels_table").rows.length;
                    let length_node = document.createElement("td");
                    length_node.innerHTML = labels_length.toString();
                    new_row.appendChild(length_node)

                    let label_node = document.createElement("td");
                    label_node.innerHTML = label;
                    label_node.id = label;
                    new_row.appendChild(label_node);

                    let pass_node = document.createElement("td");
                    let pass_btn_node = document.createElement("button");
                    pass_btn_node.innerHTML = "VIEW PASSWORD";
                    pass_node.id = label;
                    pass_btn_node.className = "view_password_btn";
                    pass_btn_node.type = "button";
                    pass_btn_node.name = label;
                    pass_node.appendChild(pass_btn_node);
                    new_row.appendChild(pass_node);

                    $("#labels_list").append(new_row);

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

});