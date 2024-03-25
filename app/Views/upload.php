<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload</title>
</head>
<body>
    <h3>Upload file and store in 64 bit formate</h3>


    <form action="/uploadImg" method="post" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit">
    </form>


    <!-- To display the image -->
    <img src="data:image/jpeg;base64,<?= isset($data)?base64_encode($data):"" ?>" width="500" height="500" alt="Image">


</body>
</html>


