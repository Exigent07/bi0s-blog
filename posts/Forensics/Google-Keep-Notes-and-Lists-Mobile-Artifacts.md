---
title: 'Google Keep - Notes and Lists: Mobile Artifacts'
author: g4rud4
author_url: 'https://twitter.com/_Nihith'
date: 2021-06-18 11:39:42
tags:
 - Android
 - Google Keep
 - DB Browser for SQLITE
 - ALEAPP
categories:
 - Forensics
 - Android
---

**tl;dr**

+ Analysing Google keep mobile artifacts.

<!--more-->

![Google Keep](logo-google-keep.png)

Google Keep is one of the best notes storing app for Android from Google can be installed through [Google Play store](https://play.google.com/store/apps/details?id=com.google.android.keep&hl=en_US&gl=US). In this blog post I am gonna explain about the Google Keep Mobile Artifacts, one can find in an android mobile dump.

The Google Keep Notes app folder can be found at the following path: `/data/data/com.google.android.keep/`

The folders of interest is `databases` and `files/1/image/original`.

The `files/1/image/original` directory contains the photos taken using/used in the app.

## Databases

So, lets have a look at the **databases** subfolder, which gives us a database file to analyse.

* keep.db - Contains information about the account details, notes, title, images added to the notes.

### Keep.db

The `keep.db` contains ~50 tables as shown:

![Listing table in keep.db](list-tables.gif)

The main tables of interest is `account`, `list_item`, `blob`, `blob_node`, `sharing`, and `tree_entity`. These tables include a lot of information related to Notes text, Title, Sharing information, Creation timestamp, Last updated timestamp etc.

Here is an example on how the data is stored in some the important tables:

#### Account Table

Main columns of interest in this table are `_id` and `name`.

* `_id` - Auto increments if we are having 2 or more Google accounts present in the device and we can use this value to map which user(`name`) created the notes with the `account_id` column in `list_item` table.

![Account Table](account-table.gif)

#### List Item Table

Main columns of interest in this table are `text`, `synced_text`, `list_parent_id`, `time_created`, `time_last_updated`, `is_deleted`.

* **Text** - This column contains the text added to the Notes
* **Synced Text** - This column contains the text synced with the google account.
* **List Parent ID** - This column contains the ID, will be autoincremented and unique for every notes. If multiple rows have same value, then it means the user created a list within the same note.
* **Is Deleted** - Gives us an info on whether the notes is deleted or not.

**Time Created** and **Time last updated** are self explanatory and both are stored in Unix Epoch Time.

![List Item table](list-item.gif)

#### blob Table

This table contains the metadata data about images present in `/files` directory. This table stores the file size, name, mime type, and extracted text from the images inserted to the notes.

![Blob Table](blob.gif)

#### blob node Table

This table is used for retrieving the created and last modifed timestamps of the images inserted into the notes. We can correlate the blob, blob_node and tree_entity and retrieve to which notes the image is added. 

![Blob Node](blob_node.gif)

#### Tree Entity Table

The main columns of intrest in table are `account_id`, `title`, `is_owner`, `last_modifier_email`, `is_deleted`, and `is_pinned`.

All the columns are self explanatory and gives us the details about the notes created.

![Tree Entity](tree-entity.gif)

[ALEAPP Parsers](https://github.com/abrignoni/ALEAPP) have been added for retrieving Title, Text, Created Time, Last Modified time, Last Modifier Email, Shared Email and the Images added to the notes will be added soon, while I continue my research on it.

Get **ALEAPP** here - https://github.com/abrignoni/ALEAPP

## References

1. **Learning Android Forensics** by *Rohit Tamma and Donnie Tindall*