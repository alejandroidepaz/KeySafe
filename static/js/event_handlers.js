$(document).ready(function(){

    $(function() {
        $('#add_password_btn').click(function() {

            var form_data = new FormData();
            var label = $("#label").val();
            form_data.append("label", label );
            form_data.append("password", $("#password").val() );

            $.ajax({
                type: 'POST',
                url: '/add_password',
                data: form_data,
                contentType: false,
                cache: false,
                processData: false,
                success: function(data) {
                    $(".modal-header button").click();
                    
                    let label_node = document.createElement("LI");
                    label_node.innerHTML = label;
                    label_node.id = label;
                    $("#labels_list").append(label_node);

                    let pass_node = document.createElement("LI");
                    let pass_btn_node = document.createElement("button");
                    pass_btn_node.innerHTML = "VIEW PASSWORD";
                    pass_node.id = label;
                    pass_btn_node.className = "view_password_btn";
                    pass_btn_node.type = "button";
                    pass_btn_node.name = label;
                    pass_node.appendChild(pass_btn_node);
                    $("#passwords_list").append(pass_node);

                    alert("We've updated your profile with the secured data!")
                },
            });
        });
    });

    $(function() {

        $('#passwords_list').on("click", ".view_password_btn", function() {

            let label = this.name;
            var form_data = new FormData();
            form_data.append("label", label);
            console.log(label);

            $.ajax({
                type: 'POST',
                url: '/view_password',
                data: form_data,
                contentType: false,
                cache: false,
                processData: false,
                success: function(data) {
                    console.log(data);
                    alert("Your Password is: " + data.decrypted);
                },
            });
        });
    });

});